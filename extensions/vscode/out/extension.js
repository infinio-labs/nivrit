"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.activate = activate;
exports.deactivate = deactivate;
const vscode = __importStar(require("vscode"));
const crypto_1 = require("./crypto");
const session_1 = require("./session");
const treeProvider_1 = require("./treeProvider");
const env_1 = require("./env");
const STATUS_SIGNED_IN = '$(shield) Nivrit';
const STATUS_SIGNED_OUT = '$(sign-in) Sign in to Nivrit';
async function activate(context) {
    (0, crypto_1.initCrypto)(context.extensionPath);
    const output = vscode.window.createOutputChannel('Nivrit');
    context.subscriptions.push(output);
    const session = new session_1.SessionManager(context.secrets);
    const treeProvider = new treeProvider_1.NivritTreeProvider(session, output);
    const statusBar = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 100);
    statusBar.command = 'nivrit.toggleSignIn';
    context.subscriptions.push(statusBar);
    const updateStatus = () => {
        if (session.isSignedIn) {
            statusBar.text = STATUS_SIGNED_IN;
            statusBar.tooltip = `Signed in as ${session.current?.user.email}\nClick to sign out`;
        }
        else {
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
        }
        catch (err) {
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
        }
        else {
            await signIn();
        }
    };
    const viewSecret = async (item) => {
        if (!item || item.kind !== treeProvider_1.TreeNodeKind.Secret)
            return;
        const value = item.context.plaintext || '[unable to decrypt]';
        const action = await vscode.window.showInformationMessage(`${item.context.secret.key}`, { modal: true, detail: value }, 'Copy');
        if (action === 'Copy') {
            await vscode.env.clipboard.writeText(value);
        }
    };
    const copySecret = async (item) => {
        if (!item || item.kind !== treeProvider_1.TreeNodeKind.Secret)
            return;
        const value = item.context.plaintext;
        if (value === undefined) {
            vscode.window.showErrorMessage('Unable to copy: secret could not be decrypted');
            return;
        }
        await vscode.env.clipboard.writeText(value);
        vscode.window.showInformationMessage(`Copied ${item.context.secret.key} to clipboard`);
    };
    const copyEnv = async (item) => {
        if (!item || item.kind !== treeProvider_1.TreeNodeKind.Environment)
            return;
        try {
            const block = await (0, env_1.buildEnvBlock)(session, item.context.project.id, item.context.environment.id, item.context.membership);
            await vscode.env.clipboard.writeText(block);
            vscode.window.showInformationMessage(`Copied .env block for ${item.context.environment.name}`);
        }
        catch (err) {
            vscode.window.showErrorMessage(`Copy .env failed: ${err?.message || err}`);
        }
    };
    const insertIntoEnv = async (item) => {
        if (!item || item.kind !== treeProvider_1.TreeNodeKind.Environment)
            return;
        try {
            const block = await (0, env_1.buildEnvBlock)(session, item.context.project.id, item.context.environment.id, item.context.membership);
            await (0, env_1.insertIntoEnvFile)(block);
            vscode.window.showInformationMessage(`Inserted .env block for ${item.context.environment.name}`);
        }
        catch (err) {
            vscode.window.showErrorMessage(`Insert .env failed: ${err?.message || err}`);
        }
    };
    context.subscriptions.push(vscode.window.registerTreeDataProvider('nivritExplorer', treeProvider), vscode.commands.registerCommand('nivrit.signIn', signIn), vscode.commands.registerCommand('nivrit.signOut', signOut), vscode.commands.registerCommand('nivrit.toggleSignIn', toggleSignIn), vscode.commands.registerCommand('nivrit.refresh', refresh), vscode.commands.registerCommand('nivrit.viewSecret', viewSecret), vscode.commands.registerCommand('nivrit.copySecret', copySecret), vscode.commands.registerCommand('nivrit.copyEnv', copyEnv), vscode.commands.registerCommand('nivrit.insertIntoEnv', insertIntoEnv));
    const restored = await session.restore();
    if (restored) {
        output.appendLine(`Restored Nivrit session for ${session.current.user.email}`);
    }
    updateStatus();
}
function deactivate() { }
//# sourceMappingURL=extension.js.map