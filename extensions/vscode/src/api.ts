import { URL } from 'url';

export interface NivritUser {
  id: string;
  email: string;
  name?: string;
  public_key: string;
  encrypted_private_key: string;
  private_key_nonce: string;
  private_key_algorithm: string;
}

export interface NivritOrg {
  id: string;
  name: string;
  slug: string;
}

export interface NivritProject {
  id: string;
  org_id: string;
  name: string;
  slug: string;
}

export interface NivritProjectMembership {
  project_id: string;
  role: string;
  encrypted_project_key: string;
  project_key_nonce: string;
  project_key_algorithm: string;
}

export interface NivritEnvironment {
  id: string;
  project_id: string;
  name: string;
  slug: string;
}

export interface NivritSecret {
  id: string;
  project_id: string;
  environment_id: string;
  folder_id?: string;
  key: string;
  encrypted_value: string;
  nonce: string;
  algorithm: string;
  version: number;
}

export class NivritApi {
  constructor(
    private readonly baseUrl: string,
    private readonly token: string
  ) {}

  private getHeaders(): Record<string, string> {
    return {
      Authorization: `Bearer ${this.token}`,
      'Content-Type': 'application/json',
      'User-Agent': 'nivrit-vscode/0.1.0',
    };
  }

  private async request<T>(path: string, init?: any): Promise<T> {
    const url = new URL(path, this.baseUrl.endsWith('/') ? this.baseUrl : `${this.baseUrl}/`).toString();
    const response = await fetch(url, {
      ...init,
      headers: { ...this.getHeaders(), ...(init?.headers || {}) },
    });

    if (!response.ok) {
      let body = '';
      try {
        body = await response.text();
      } catch {}
      throw new Error(`Nivrit API error ${response.status}: ${body || response.statusText}`);
    }

    if (response.status === 204) {
      return undefined as unknown as T;
    }

    return response.json() as Promise<T>;
  }

  async getMe(): Promise<NivritUser> {
    return this.request<NivritUser>('/users/me');
  }

  async listOrgs(): Promise<NivritOrg[]> {
    return this.request<NivritOrg[]>('/users/me/orgs');
  }

  async listOrgProjects(orgId: string): Promise<NivritProject[]> {
    return this.request<NivritProject[]>(`/orgs/${encodeURIComponent(orgId)}/projects`);
  }

  async listMyProjects(): Promise<NivritProjectMembership[]> {
    return this.request<NivritProjectMembership[]>('/users/me/projects');
  }

  async listEnvironments(projectId: string): Promise<NivritEnvironment[]> {
    return this.request<NivritEnvironment[]>(`/projects/${encodeURIComponent(projectId)}/environments`);
  }

  async listSecrets(projectId: string, environmentId: string): Promise<NivritSecret[]> {
    const params = new URLSearchParams();
    params.set('environment_id', environmentId);
    return this.request<NivritSecret[]>(
      `/projects/${encodeURIComponent(projectId)}/secrets?${params.toString()}`
    );
  }

  async getSecret(projectId: string, environmentId: string, key: string): Promise<NivritSecret> {
    const params = new URLSearchParams();
    params.set('environment_id', environmentId);
    return this.request<NivritSecret>(
      `/projects/${encodeURIComponent(projectId)}/secrets/${encodeURIComponent(key)}?${params.toString()}`
    );
  }
}
