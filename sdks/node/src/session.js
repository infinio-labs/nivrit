const crypto = require('crypto');
const { NivritClient } = require('./client');

class NivritSession {
  constructor(baseUrl, token, crypto) {
    this.baseUrl = baseUrl;
    this.token = token;
    this.crypto = crypto;
    this.client = new NivritClient(baseUrl, token);
    this.user = null;
    this.privateKey = null;
    // project_id -> Map(version -> decapsulated key). A project that's never
    // been rotated has exactly one entry (ADR 0008).
    this.projectKeys = new Map();
  }

  static async fromPat(baseUrl, pat, password, crypto) {
    const session = new NivritSession(baseUrl, pat, crypto);
    await session.authenticate(password);
    return session;
  }

  async authenticate(password) {
    this.user = await this.client.getMe();
    this.privateKey = this.crypto.decryptPrivateKey(
      this.user.encrypted_private_key,
      this.user.private_key_nonce,
      password
    );
  }

  async listOrgs() {
    return this.client.listOrgs();
  }

  async listProjects(orgId) {
    const [projects, memberships] = await Promise.all([
      this.client.listOrgProjects(orgId),
      this.client.listMyProjects(),
    ]);
    const membershipMap = new Map(memberships.map((m) => [m.project_id, m]));
    return projects.map((p) => ({ ...p, membership: membershipMap.get(p.project_id) }));
  }

  /**
   * Every project-key version this account has been granted, decapsulated
   * and cached, oldest first (ADR 0008). Idempotent per project per process
   * -- call again after a rotation you triggered yourself to pick up the new
   * version without a fresh login.
   */
  async loadProjectKeys(projectId) {
    const entries = await this.client.listKeyVersions(projectId);
    const versions = new Map();
    for (const entry of entries) {
      if (!entry.encrypted_project_key) continue;
      const key = this.crypto.decapsulateProjectKey(entry.encrypted_project_key, this.privateKey);
      versions.set(entry.version, key);
    }
    this.projectKeys.set(projectId, versions);
    return versions;
  }

  /** The key for a specific project-key version, loading the cache first if
   * needed. Omit `version` for the current (highest) one. */
  async getProjectKey(projectId, version) {
    let versions = this.projectKeys.get(projectId);
    if (!versions) versions = await this.loadProjectKeys(projectId);
    const resolvedVersion = version ?? Math.max(...versions.keys());
    const key = versions.get(resolvedVersion);
    if (!key) {
      throw new Error(
        `no cached key for project ${projectId} version ${resolvedVersion}; call loadProjectKeys() again to pick up any versions granted since`
      );
    }
    return key;
  }

  /** The version new secret writes should use -- for building a
   * createSecret/setSecret request's `project_key_version` field. */
  async currentProjectKeyVersion(projectId) {
    let versions = this.projectKeys.get(projectId);
    if (!versions) versions = await this.loadProjectKeys(projectId);
    return Math.max(...versions.keys());
  }

  async listSecrets(projectId, environmentId) {
    const secrets = await this.client.listSecrets(projectId, environmentId);
    return Promise.all(
      secrets.map(async (s) => {
        const projectKey = await this.getProjectKey(projectId, s.project_key_version ?? 1);
        return { ...s, value: this.crypto.decryptValue(s.encrypted_value, s.nonce, projectKey) };
      })
    );
  }

  async getSecret(projectId, environmentId, key) {
    const secret = await this.client.getSecret(projectId, environmentId, key);
    const projectKey = await this.getProjectKey(projectId, secret.project_key_version ?? 1);
    return { ...secret, value: this.crypto.decryptValue(secret.encrypted_value, secret.nonce, projectKey) };
  }

  /** Invite a user to a project by email, encapsulating the project's
   * current key version to their public key. Grants whichever version is
   * current, not a hardcoded version 1, so an invite after a rotation
   * doesn't hand out a superseded key (ADR 0008). */
  async inviteMember(projectId, email, role) {
    const projectKey = await this.getProjectKey(projectId);
    const recipient = await this.client.getPublicKey(email, projectId);
    const encapsulated = this.crypto.encapsulateProjectKey(projectKey, recipient.public_key);
    return this.client.inviteMember(projectId, { email, role, encrypted_project_key: encapsulated });
  }

  /**
   * Mint a new project-key version and grant it to exactly the project's
   * current members (ADR 0008). No existing secret is touched. A removed
   * member simply never receives this grant, so they're locked out of
   * everything created from this point forward.
   */
  async rotateProjectKey(projectId) {
    // Proves we hold a valid key for this project before bothering to mint
    // the next version; the actual replacement key is generated fresh below.
    await this.getProjectKey(projectId);

    const members = await this.client.listMembers(projectId);
    const newKey = crypto.randomBytes(32).toString('base64');

    const grants = members.map((member) => {
      const encapsulated = this.crypto.encapsulateProjectKey(newKey, member.public_key);
      return {
        user_id: member.user_id,
        encrypted_project_key: Buffer.from(JSON.stringify(encapsulated)).toString('base64'),
        project_key_nonce: '',
        project_key_algorithm: encapsulated.suite,
      };
    });

    const result = await this.client.rotateKey(projectId, { grants });

    const versions = this.projectKeys.get(projectId) || new Map();
    versions.set(result.version, newKey);
    this.projectKeys.set(projectId, versions);

    return { version: result.version, grantedTo: grants.length };
  }
}

module.exports = { NivritSession };
