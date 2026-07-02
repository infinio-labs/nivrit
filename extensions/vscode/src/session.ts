import * as vscode from 'vscode';
import { NivritApi, NivritProjectMembership, NivritUser } from './api';
import { decryptPrivateKey, decapsulateProjectKey, EncapsulatedProjectKey } from './crypto';

const TOKEN_KEY = 'nivrit.token';
const USER_KEY = 'nivrit.user';
const PRIVATE_KEY_KEY = 'nivrit.privateKey';

export interface SessionState {
  token: string;
  user: NivritUser;
  privateKey: string;
}

export class SessionManager {
  private state: SessionState | null = null;
  private readonly projectKeyCache = new Map<string, string>();

  constructor(private readonly secrets: vscode.SecretStorage) {}

  get isSignedIn(): boolean {
    return this.state !== null;
  }

  get current(): SessionState | null {
    return this.state;
  }

  async restore(): Promise<boolean> {
    const token = await this.secrets.get(TOKEN_KEY);
    if (!token) return false;

    try {
      const userJson = await this.secrets.get(USER_KEY);
      const privateKey = await this.secrets.get(PRIVATE_KEY_KEY);
      if (!userJson || !privateKey) return false;

      const user: NivritUser = JSON.parse(userJson);
      const api = new NivritApi(this.baseUrl, token);
      await api.getMe();

      this.state = { token, user, privateKey };
      return true;
    } catch {
      await this.clear();
      return false;
    }
  }

  async signIn(): Promise<void> {
    const baseUrl = this.baseUrl;
    const token = await vscode.window.showInputBox({
      prompt: 'Nivrit personal access token',
      password: true,
      ignoreFocusOut: true,
      validateInput: (v) => (v?.trim() ? undefined : 'Token is required'),
    });
    if (!token) return;

    const password = await vscode.window.showInputBox({
      prompt: 'Your Nivrit account password',
      password: true,
      ignoreFocusOut: true,
      validateInput: (v) => (v ? undefined : 'Password is required'),
    });
    if (!password) return;

    const api = new NivritApi(baseUrl, token);
    const user = await api.getMe();

    let privateKey: string;
    try {
      privateKey = decryptPrivateKey(user.encrypted_private_key, user.private_key_nonce, password);
    } catch (err: any) {
      throw new Error(`Could not decrypt private key. Wrong password? ${err?.message || err}`);
    }

    await this.secrets.store(TOKEN_KEY, token);
    await this.secrets.store(USER_KEY, JSON.stringify(user));
    await this.secrets.store(PRIVATE_KEY_KEY, privateKey);

    this.state = { token, user, privateKey };
  }

  async signOut(): Promise<void> {
    await this.clear();
  }

  async clear(): Promise<void> {
    await this.secrets.delete(TOKEN_KEY);
    await this.secrets.delete(USER_KEY);
    await this.secrets.delete(PRIVATE_KEY_KEY);
    this.state = null;
  }

  createApi(): NivritApi {
    if (!this.state) throw new Error('Not signed in');
    return new NivritApi(this.baseUrl, this.state.token);
  }

  getProjectKey(membership: NivritProjectMembership): string {
    if (!this.state) throw new Error('Not signed in');

    const cached = this.projectKeyCache.get(membership.project_id);
    if (cached) return cached;

    const jsonBytes = Buffer.from(membership.encrypted_project_key, 'base64');
    const encapsulated: EncapsulatedProjectKey = JSON.parse(jsonBytes.toString('utf-8'));
    const key = decapsulateProjectKey(encapsulated, this.state.privateKey);
    this.projectKeyCache.set(membership.project_id, key);
    return key;
  }

  clearProjectKeys(): void {
    this.projectKeyCache.clear();
  }

  private get baseUrl(): string {
    const cfg = vscode.workspace.getConfiguration('nivrit');
    return cfg.get<string>('apiUrl') || 'http://localhost:4000';
  }
}
