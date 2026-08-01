class NivritClient {
  constructor(baseUrl, token) {
    this.baseUrl = baseUrl.replace(/\/$/, '');
    this.token = token;
  }

  async request(path, init = {}) {
    const url = `${this.baseUrl}${path}`;
    const headers = {
      Authorization: `Bearer ${this.token}`,
      'Content-Type': 'application/json',
      ...init.headers,
    };
    const res = await fetch(url, { ...init, headers });
    const text = await res.text();
    if (!res.ok) throw new Error(`Nivrit API error ${res.status}: ${text}`);
    return text ? JSON.parse(text) : undefined;
  }

  getMe() {
    return this.request('/users/me');
  }

  listOrgs() {
    return this.request('/users/me/orgs');
  }

  listMyProjects() {
    return this.request('/users/me/projects');
  }

  listOrgProjects(orgId) {
    return this.request(`/orgs/${encodeURIComponent(orgId)}/projects`);
  }

  listEnvironments(projectId) {
    return this.request(`/projects/${encodeURIComponent(projectId)}/environments`);
  }

  listSecrets(projectId, environmentId) {
    return this.request(`/projects/${encodeURIComponent(projectId)}/secrets?environment_id=${encodeURIComponent(environmentId)}`);
  }

  getSecret(projectId, environmentId, key) {
    return this.request(`/projects/${encodeURIComponent(projectId)}/secrets/${encodeURIComponent(key)}?environment_id=${encodeURIComponent(environmentId)}`);
  }

  listSecretVersions(projectId, environmentId, key) {
    return this.request(`/projects/${encodeURIComponent(projectId)}/secrets/${encodeURIComponent(key)}/versions?environment_id=${encodeURIComponent(environmentId)}`);
  }

  restoreSecret(projectId, environmentId, key, version) {
    return this.request(`/projects/${encodeURIComponent(projectId)}/secrets/${encodeURIComponent(key)}/restore`, {
      method: 'POST',
      body: JSON.stringify({ environment_id: environmentId, version }),
    });
  }

  listFolders(projectId, environmentId) {
    return this.request(`/projects/${encodeURIComponent(projectId)}/folders?environment_id=${encodeURIComponent(environmentId)}`);
  }

  createFolder(projectId, environmentId, name, path) {
    return this.request(`/projects/${encodeURIComponent(projectId)}/folders`, {
      method: 'POST',
      body: JSON.stringify({ environment_id: environmentId, name, path }),
    });
  }

  deleteFolder(projectId, folderId) {
    return this.request(`/projects/${encodeURIComponent(projectId)}/folders/${encodeURIComponent(folderId)}`, { method: 'DELETE' });
  }

  listImports(projectId, environmentId) {
    return this.request(`/projects/${encodeURIComponent(projectId)}/imports?environment_id=${encodeURIComponent(environmentId)}`);
  }

  createImport(projectId, environmentId, sourceEnvironmentId, position = 0) {
    return this.request(`/projects/${encodeURIComponent(projectId)}/imports`, {
      method: 'POST',
      body: JSON.stringify({ environment_id: environmentId, source_environment_id: sourceEnvironmentId, position }),
    });
  }

  deleteImport(projectId, importId) {
    return this.request(`/projects/${encodeURIComponent(projectId)}/imports/${encodeURIComponent(importId)}`, { method: 'DELETE' });
  }

  listTags(projectId) {
    return this.request(`/projects/${encodeURIComponent(projectId)}/tags`);
  }

  createTag(projectId, name, color = '#888888') {
    return this.request(`/projects/${encodeURIComponent(projectId)}/tags`, {
      method: 'POST',
      body: JSON.stringify({ name, color }),
    });
  }

  deleteTag(projectId, tagId) {
    return this.request(`/projects/${encodeURIComponent(projectId)}/tags/${encodeURIComponent(tagId)}`, { method: 'DELETE' });
  }

  listSecretTags(projectId, environmentId, key) {
    return this.request(`/projects/${encodeURIComponent(projectId)}/secrets/${encodeURIComponent(key)}/tags?environment_id=${encodeURIComponent(environmentId)}`);
  }

  tagSecret(projectId, environmentId, key, tagId) {
    return this.request(`/projects/${encodeURIComponent(projectId)}/secrets/${encodeURIComponent(key)}/tags`, {
      method: 'POST',
      body: JSON.stringify({ environment_id: environmentId, tag_id: tagId }),
    });
  }

  untagSecret(projectId, environmentId, key, tagId) {
    return this.request(`/projects/${encodeURIComponent(projectId)}/secrets/${encodeURIComponent(key)}/tags/${encodeURIComponent(tagId)}?environment_id=${encodeURIComponent(environmentId)}`, { method: 'DELETE' });
  }

  createOrg(body) {
    return this.request('/orgs', { method: 'POST', body: JSON.stringify(body) });
  }

  createProject(body) {
    return this.request('/projects', { method: 'POST', body: JSON.stringify(body) });
  }

  createEnvironment(projectId, body) {
    return this.request(`/projects/${encodeURIComponent(projectId)}/environments`, { method: 'POST', body: JSON.stringify(body) });
  }

  createSecret(projectId, body) {
    return this.request(`/projects/${encodeURIComponent(projectId)}/secrets`, { method: 'POST', body: JSON.stringify(body) });
  }

  createPat(body) {
    return this.request('/auth/pat', { method: 'POST', body: JSON.stringify(body) });
  }

  /** Look up a user's public key by email, to encapsulate a project key to
   * them (invite, or a rotation grant). Requires Member+ on `projectId`. */
  getPublicKey(email, projectId) {
    return this.request(
      `/users/public-key?email=${encodeURIComponent(email)}&project_id=${encodeURIComponent(projectId)}`
    );
  }

  // Versioned project keys (ADR 0008)

  /** Current members of a project and the public key a rotation grant should
   * be encapsulated to. */
  listMembers(projectId) {
    return this.request(`/projects/${encodeURIComponent(projectId)}/members`);
  }

  inviteMember(projectId, body) {
    return this.request(`/projects/${encodeURIComponent(projectId)}/members`, {
      method: 'POST',
      body: JSON.stringify(body),
    });
  }

  /** Every project-key version the caller has been granted, oldest first --
   * what's needed to decrypt the project's full secret history, not just
   * what's current. */
  listKeyVersions(projectId) {
    return this.request(`/projects/${encodeURIComponent(projectId)}/key-versions`);
  }

  /** Mint the next project-key version, granted to exactly the supplied
   * roster. The server independently verifies the roster matches current
   * membership. */
  rotateKey(projectId, body) {
    return this.request(`/projects/${encodeURIComponent(projectId)}/rotate-key`, {
      method: 'POST',
      body: JSON.stringify(body),
    });
  }
}

module.exports = { NivritClient };
