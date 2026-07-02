import * as vscode from 'vscode';
import { initCrypto } from './crypto';
import { SessionManager } from './session';
import { NivritTreeProvider, NivritTreeItem, TreeNodeKind } from './treeProvider';
import { buildEnvBlock, insertIntoEnvFile } from './env';

const STATUS_SIGNED_IN = '$(shield) Nivrit';
const STATUS_SIGNED_OUT = '$(sign-in) Sign in to Nivrit';

export async function activate(context: vscode.ExtensionContext): Promise<void> {
  initCrypto(context.extensionPath);

  const output = vscode.window.createOutputChannel('Nivrit');
  context.subscriptions.push(output);

  const session = new SessionManager(context.secrets);
  const treeProvider = new NivritTreeProvider(session, output);

  const statusBar = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 100);
  statusBar.command = 'nivrit.toggleSignIn';
  context.subscriptions.push(statusBar);

  const updateStatus = () => {
    if (session.isSignedIn) {
      statusBar.text = STATUS_SIGNED_IN;
      statusBar.tooltip = `Signed in as ${session.current?.user.email}\nClick to sign out`;
    } else {
      statusBar.text = STATUS_SIGNED_OUT;
      statusBar.tooltip = 'Click to sign in to Nivrit';
    }
    statusBar.show();
  };

  const refresh = () => {
    treeProvider.refresh();
    updateStatus();
  };

  const signIn = async () => {
    try {
      await session.signIn();
      vscode.window.showInformationMessage('Signed in to Nivrit');
      refresh();
    } catch (err: any) {
      vscode.window.showErrorMessage(`Sign in failed: ${err?.message || err}`);
    }
  };

  const signOut = async () => {
    await session.signOut();
    vscode.window.showInformationMessage('Signed out of Nivrit');
    refresh();
  };

  const toggleSignIn = async () => {
    if (session.isSignedIn) {
      await signOut();
    } else {
      await signIn();
    }
  };

  const viewSecret = async (item?: NivritTreeItem) => {
    if (!item || item.kind !== TreeNodeKind.Secret) return;
    const value = item.context.plaintext || '[unable to decrypt]';
    const action = await vscode.window.showInformationMessage(
      `${item.context.secret!.key}`,
      { modal: true, detail: value },
      'Copy'
    );
    if (action === 'Copy') {
      await vscode.env.clipboard.writeText(value);
    }
  };

  const copySecret = async (item?: NivritTreeItem) => {
    if (!item || item.kind !== TreeNodeKind.Secret) return;
    const value = item.context.plaintext;
    if (value === undefined) {
      vscode.window.showErrorMessage('Unable to copy: secret could not be decrypted');
      return;
    }
    await vscode.env.clipboard.writeText(value);
    vscode.window.showInformationMessage(`Copied ${item.context.secret!.key} to clipboard`);
  };

  const copyEnv = async (item?: NivritTreeItem) => {
    if (!item || item.kind !== TreeNodeKind.Environment) return;
    try {
      const block = await buildEnvBlock(
        session,
        item.context.project!.id,
        item.context.environment!.id,
        item.context.membership
      );
      await vscode.env.clipboard.writeText(block);
      vscode.window.showInformationMessage(`Copied .env block for ${item.context.environment!.name}`);
    } catch (err: any) {
      vscode.window.showErrorMessage(`Copy .env failed: ${err?.message || err}`);
    }
  };

  const insertIntoEnv = async (item?: NivritTreeItem) => {
    if (!item || item.kind !== TreeNodeKind.Environment) return;
    try {
      const block = await buildEnvBlock(
        session,
        item.context.project!.id,
        item.context.environment!.id,
        item.context.membership
      );
      await insertIntoEnvFile(block);
      vscode.window.showInformationMessage(`Inserted .env block for ${item.context.environment!.name}`);
    } catch (err: any) {
      vscode.window.showErrorMessage(`Insert .env failed: ${err?.message || err}`);
    }
  };

  context.subscriptions.push(
    vscode.window.registerTreeDataProvider('nivritExplorer', treeProvider),
    vscode.commands.registerCommand('nivrit.signIn', signIn),
    vscode.commands.registerCommand('nivrit.signOut', signOut),
    vscode.commands.registerCommand('nivrit.toggleSignIn', toggleSignIn),
    vscode.commands.registerCommand('nivrit.refresh', refresh),
    vscode.commands.registerCommand('nivrit.viewSecret', viewSecret),
    vscode.commands.registerCommand('nivrit.copySecret', copySecret),
    vscode.commands.registerCommand('nivrit.copyEnv', copyEnv),
    vscode.commands.registerCommand('nivrit.insertIntoEnv', insertIntoEnv)
  );

  const restored = await session.restore();
  if (restored) {
    output.appendLine(`Restored Nivrit session for ${session.current!.user.email}`);
  }
  updateStatus();
}

export function deactivate(): void {}
