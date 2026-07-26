/// <reference types="vite/client" />
const API_URL =
  (typeof import.meta.env !== 'undefined' && import.meta.env.VITE_API_URL) ||
  'http://localhost:4000';

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
  if (!res.ok) throw new Error('login failed');
  return res.json();
}

export async function loginTotp(tempToken: string, code: string): Promise<LoginResponse> {
  const res = await fetch(`${API_URL}/auth/login/totp`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ temp_token: tempToken, code }),
  });
  if (!res.ok) throw new Error('TOTP login failed');
  return res.json();
}

export async function register(body: RegisterRequest): Promise<RegisterResponse> {
  const res = await fetch(`${API_URL}/auth/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error('registration failed');
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
  if (!res.ok) throw new Error('invalid reset token or recovery code');
  return res.json();
}

export interface ResetPasswordRequest {
  token: string;
  recovery_auth_hash: string;
  new_auth_hash: string;
  encrypted_private_key: string;
  private_key_nonce: string;
  private_key_algorithm: string;
}

/// Step 2: upload the private key re-wrapped under the new password.
export async function resetPassword(body: ResetPasswordRequest): Promise<LoginResponse> {
  const res = await fetch(`${API_URL}/auth/reset-password`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error('reset failed');
  return res.json();
}

// OAuth

export async function oauthAuthorizeUrl(provider: 'google' | 'github'): Promise<{ url: string; state: string }> {
  const res = await fetch(`${API_URL}/auth/oauth/authorize`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ provider }),
  });
  if (!res.ok) throw new Error('oauth authorize failed');
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
  if (!res.ok) throw new Error('oauth callback failed');
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
  if (!res.ok) throw new Error('oauth setup failed');
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
  if (!res.ok) throw new Error('totp setup failed');
  return res.json();
}

export async function verifyTotp(token: string, code: string): Promise<{ enabled: boolean }> {
  const res = await fetch(`${API_URL}/auth/totp/verify`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
    body: JSON.stringify({ code }),
  });
  if (!res.ok) throw new Error('totp verify failed');
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
  if (!res.ok) throw new Error('totp disable failed');
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

export async function getPublicKey(token: string, email: string): Promise<PublicKeyResponse> {
  const res = await fetch(`${API_URL}/users/public-key?email=${encodeURIComponent(email)}`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!res.ok) throw new Error('failed to fetch public key');
  return res.json();
}

export async function setSecret(
  token: string,
  projectId: string,
  environmentId: string,
  key: string,
  ciphertext: string,
  nonce: string
): Promise<void> {
  const res = await fetch(`${API_URL}/projects/${projectId}/secrets`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${token}`,
    },
    body: JSON.stringify({ environment_id: environmentId, key, encrypted_value: ciphertext, nonce }),
  });
  if (!res.ok) throw new Error('set secret failed');
}

export async function getSecret(
  token: string,
  projectId: string,
  environmentId: string,
  key: string
): Promise<{ encrypted_value: string; nonce: string }> {
  const res = await fetch(
    `${API_URL}/projects/${projectId}/secrets/${key}?environment_id=${environmentId}`,
    { headers: { Authorization: `Bearer ${token}` } }
  );
  if (!res.ok) throw new Error('get secret failed');
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

export async function listSecrets(
  token: string,
  projectId: string,
  environmentId: string
): Promise<SecretListItem[]> {
  const res = await fetch(
    `${API_URL}/projects/${projectId}/secrets?environment_id=${environmentId}`,
    { headers: { Authorization: `Bearer ${token}` } }
  );
  if (!res.ok) throw new Error('list secrets failed');
  return res.json();
}

export async function deleteSecret(
  token: string,
  projectId: string,
  environmentId: string,
  key: string
): Promise<void> {
  const res = await fetch(
    `${API_URL}/projects/${projectId}/secrets/${key}?environment_id=${environmentId}`,
    {
      method: 'DELETE',
      headers: { Authorization: `Bearer ${token}` },
    }
  );
  if (!res.ok) throw new Error('delete secret failed');
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
