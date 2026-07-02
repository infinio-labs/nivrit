import * as vscode from 'vscode';
import * as path from 'path';
import { NivritSecret, NivritProjectMembership } from './api';
import { SessionManager } from './session';
import { decryptValue } from './crypto';

export function formatEnvLine(key: string, value: string): string {
  const escaped = value
    .replace(/\\/g, '\\\\')
    .replace(/"/g, '\\"')
    .replace(/\n/g, '\\n')
    .replace(/\r/g, '\\r');
  return `${key}="${escaped}"`;
}

export function formatEnvContent(secrets: Array<{ key: string; value: string }>): string {
  return secrets.map((s) => formatEnvLine(s.key, s.value)).join('\n') + '\n';
}

export async function buildEnvBlock(
  session: SessionManager,
  projectId: string,
  environmentId: string,
  membership?: NivritProjectMembership
): Promise<string> {
  if (!membership) throw new Error('No project membership; cannot decrypt secrets');

  const api = session.createApi();
  const secrets = await api.listSecrets(projectId, environmentId);
  const projectKey = session.getProjectKey(membership);

  const entries = secrets.map((secret) => {
    const value = decryptValue(secret.encrypted_value, secret.nonce, projectKey);
    return { key: secret.key, value };
  });

  return formatEnvContent(entries);
}

export async function findEnvFileUri(): Promise<vscode.Uri | undefined> {
  const active = vscode.window.activeTextEditor?.document.uri;
  if (active && path.basename(active.fsPath).startsWith('.env')) {
    return active;
  }

  const files = await vscode.workspace.findFiles('.env*', '**/node_modules/**', 20);
  if (files.length === 1) return files[0];

  if (files.length > 1) {
    const picked = await vscode.window.showQuickPick(
      files.map((f) => ({ label: vscode.workspace.asRelativePath(f), uri: f })),
      { placeHolder: 'Select a .env file' }
    );
    return picked?.uri;
  }

  const folders = vscode.workspace.workspaceFolders;
  if (!folders || folders.length === 0) return undefined;
  if (folders.length === 1) return vscode.Uri.joinPath(folders[0].uri, '.env');

  const picked = await vscode.window.showQuickPick(
    folders.map((f) => ({ label: f.name, uri: vscode.Uri.joinPath(f.uri, '.env') })),
    { placeHolder: 'Select workspace folder' }
  );
  return picked?.uri;
}

export async function insertIntoEnvFile(block: string): Promise<void> {
  const uri = await findEnvFileUri();
  if (!uri) throw new Error('No .env file found. Create one first.');

  let existing = '';
  try {
    existing = Buffer.from(await vscode.workspace.fs.readFile(uri)).toString('utf-8');
  } catch {
    existing = '';
  }

  const sep = existing.length > 0 && !existing.endsWith('\n') ? '\n' : '';
  const updated = existing + sep + `# Nivrit injected\n${block}`;

  await vscode.workspace.fs.writeFile(uri, Buffer.from(updated, 'utf-8'));
  const doc = await vscode.workspace.openTextDocument(uri);
  await vscode.window.showTextDocument(doc);
}
