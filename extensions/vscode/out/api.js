"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.NivritApi = void 0;
const url_1 = require("url");
class NivritApi {
    baseUrl;
    token;
    constructor(baseUrl, token) {
        this.baseUrl = baseUrl;
        this.token = token;
    }
    getHeaders() {
        return {
            Authorization: `Bearer ${this.token}`,
            'Content-Type': 'application/json',
            'User-Agent': 'nivrit-vscode/0.1.0',
        };
    }
    async request(path, init) {
        const url = new url_1.URL(path, this.baseUrl.endsWith('/') ? this.baseUrl : `${this.baseUrl}/`).toString();
        const response = await fetch(url, {
            ...init,
            headers: { ...this.getHeaders(), ...(init?.headers || {}) },
        });
        if (!response.ok) {
            let body = '';
            try {
                body = await response.text();
            }
            catch { }
            throw new Error(`Nivrit API error ${response.status}: ${body || response.statusText}`);
        }
        if (response.status === 204) {
            return undefined;
        }
        return response.json();
    }
    async getMe() {
        return this.request('/users/me');
    }
    async listOrgs() {
        return this.request('/users/me/orgs');
    }
    async listOrgProjects(orgId) {
        return this.request(`/orgs/${encodeURIComponent(orgId)}/projects`);
    }
    async listMyProjects() {
        return this.request('/users/me/projects');
    }
    async listEnvironments(projectId) {
        return this.request(`/projects/${encodeURIComponent(projectId)}/environments`);
    }
    async listSecrets(projectId, environmentId) {
        const params = new URLSearchParams();
        params.set('environment_id', environmentId);
        return this.request(`/projects/${encodeURIComponent(projectId)}/secrets?${params.toString()}`);
    }
    async getSecret(projectId, environmentId, key) {
        const params = new URLSearchParams();
        params.set('environment_id', environmentId);
        return this.request(`/projects/${encodeURIComponent(projectId)}/secrets/${encodeURIComponent(key)}?${params.toString()}`);
    }
}
exports.NivritApi = NivritApi;
//# sourceMappingURL=api.js.map