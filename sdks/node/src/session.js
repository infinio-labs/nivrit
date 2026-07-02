const { NivritClient } = require('./client');

class NivritSession {
  constructor(baseUrl, token, crypto) {
    this.baseUrl = baseUrl;
    this.token = token;
    this.crypto = crypto;
    this.client = new NivritClient(baseUrl, token);
    this.user = null;
    this.privateKey = null;
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

  getProjectKey(membership) {
    if (!membership) throw new Error('No membership for project');
    const cached = this.projectKeys.get(membership.project_id);
    if (cached) return cached;
    const key = this.crypto.decapsulateProjectKey(membership.encrypted_project_key, this.privateKey);
    this.projectKeys.set(membership.project_id, key);
    return key;
  }

  async listSecrets(projectId, environmentId) {
    const secrets = await this.client.listSecrets(projectId, environmentId);
    const memberships = await this.client.listMyProjects();
    const membership = memberships.find((m) => m.project_id === projectId);
    const projectKey = this.getProjectKey(membership);
    return secrets.map((s) => ({
      ...s,
      value: this.crypto.decryptValue(s.encrypted_value, s.nonce, projectKey),
    }));
  }

  async getSecret(projectId, environmentId, key) {
    const secret = await this.client.getSecret(projectId, environmentId, key);
    const memberships = await this.client.listMyProjects();
    const membership = memberships.find((m) => m.project_id === projectId);
    const projectKey = this.getProjectKey(membership);
    return { ...secret, value: this.crypto.decryptValue(secret.encrypted_value, secret.nonce, projectKey) };
  }
}

module.exports = { NivritSession };
