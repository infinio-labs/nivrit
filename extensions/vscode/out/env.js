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
exports.formatEnvLine = formatEnvLine;
exports.formatEnvContent = formatEnvContent;
exports.buildEnvBlock = buildEnvBlock;
exports.findEnvFileUri = findEnvFileUri;
exports.insertIntoEnvFile = insertIntoEnvFile;
const vscode = __importStar(require("vscode"));
const path = __importStar(require("path"));
const crypto_1 = require("./crypto");
function formatEnvLine(key, value) {
    const escaped = value
        .replace(/\\/g, '\\\\')
        .replace(/"/g, '\\"')
        .replace(/\n/g, '\\n')
        .replace(/\r/g, '\\r');
    return `${key}="${escaped}"`;
}
function formatEnvContent(secrets) {
    return secrets.map((s) => formatEnvLine(s.key, s.value)).join('\n') + '\n';
}
async function buildEnvBlock(session, projectId, environmentId, membership) {
    if (!membership)
        throw new Error('No project membership; cannot decrypt secrets');
    const api = session.createApi();
    const secrets = await api.listSecrets(projectId, environmentId);
    const projectKey = session.getProjectKey(membership);
    const entries = secrets.map((secret) => {
        const value = (0, crypto_1.decryptValue)(secret.encrypted_value, secret.nonce, projectKey);
        return { key: secret.key, value };
    });
    return formatEnvContent(entries);
}
async function findEnvFileUri() {
    const active = vscode.window.activeTextEditor?.document.uri;
    if (active && path.basename(active.fsPath).startsWith('.env')) {
        return active;
    }
    const files = await vscode.workspace.findFiles('.env*', '**/node_modules/**', 20);
    if (files.length === 1)
        return files[0];
    if (files.length > 1) {
        const picked = await vscode.window.showQuickPick(files.map((f) => ({ label: vscode.workspace.asRelativePath(f), uri: f })), { placeHolder: 'Select a .env file' });
        return picked?.uri;
    }
    const folders = vscode.workspace.workspaceFolders;
    if (!folders || folders.length === 0)
        return undefined;
    if (folders.length === 1)
        return vscode.Uri.joinPath(folders[0].uri, '.env');
    const picked = await vscode.window.showQuickPick(folders.map((f) => ({ label: f.name, uri: vscode.Uri.joinPath(f.uri, '.env') })), { placeHolder: 'Select workspace folder' });
    return picked?.uri;
}
async function insertIntoEnvFile(block) {
    const uri = await findEnvFileUri();
    if (!uri)
        throw new Error('No .env file found. Create one first.');
    let existing = '';
    try {
        existing = Buffer.from(await vscode.workspace.fs.readFile(uri)).toString('utf-8');
    }
    catch {
        existing = '';
    }
    const sep = existing.length > 0 && !existing.endsWith('\n') ? '\n' : '';
    const updated = existing + sep + `# Nivrit injected\n${block}`;
    await vscode.workspace.fs.writeFile(uri, Buffer.from(updated, 'utf-8'));
    const doc = await vscode.workspace.openTextDocument(uri);
    await vscode.window.showTextDocument(doc);
}
//# sourceMappingURL=env.js.map