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
exports.SessionManager = void 0;
const vscode = __importStar(require("vscode"));
const api_1 = require("./api");
const crypto_1 = require("./crypto");
const TOKEN_KEY = 'nivrit.token';
const USER_KEY = 'nivrit.user';
const PRIVATE_KEY_KEY = 'nivrit.privateKey';
class SessionManager {
    secrets;
    state = null;
    projectKeyCache = new Map();
    constructor(secrets) {
        this.secrets = secrets;
    }
    get isSignedIn() {
        return this.state !== null;
    }
    get current() {
        return this.state;
    }
    async restore() {
        const token = await this.secrets.get(TOKEN_KEY);
        if (!token)
            return false;
        try {
            const userJson = await this.secrets.get(USER_KEY);
            const privateKey = await this.secrets.get(PRIVATE_KEY_KEY);
            if (!userJson || !privateKey)
                return false;
            const user = JSON.parse(userJson);
            const api = new api_1.NivritApi(this.baseUrl, token);
            await api.getMe();
            this.state = { token, user, privateKey };
            return true;
        }
        catch {
            await this.clear();
            return false;
        }
    }
    async signIn() {
        const baseUrl = this.baseUrl;
        const token = await vscode.window.showInputBox({
            prompt: 'Nivrit personal access token',
            password: true,
            ignoreFocusOut: true,
            validateInput: (v) => (v?.trim() ? undefined : 'Token is required'),
        });
        if (!token)
            return;
        const password = await vscode.window.showInputBox({
            prompt: 'Your Nivrit account password',
            password: true,
            ignoreFocusOut: true,
            validateInput: (v) => (v ? undefined : 'Password is required'),
        });
        if (!password)
            return;
        const api = new api_1.NivritApi(baseUrl, token);
        const user = await api.getMe();
        let privateKey;
        try {
            privateKey = (0, crypto_1.decryptPrivateKey)(user.encrypted_private_key, user.private_key_nonce, password);
        }
        catch (err) {
            throw new Error(`Could not decrypt private key. Wrong password? ${err?.message || err}`);
        }
        await this.secrets.store(TOKEN_KEY, token);
        await this.secrets.store(USER_KEY, JSON.stringify(user));
        await this.secrets.store(PRIVATE_KEY_KEY, privateKey);
        this.state = { token, user, privateKey };
    }
    async signOut() {
        await this.clear();
    }
    async clear() {
        await this.secrets.delete(TOKEN_KEY);
        await this.secrets.delete(USER_KEY);
        await this.secrets.delete(PRIVATE_KEY_KEY);
        this.state = null;
    }
    createApi() {
        if (!this.state)
            throw new Error('Not signed in');
        return new api_1.NivritApi(this.baseUrl, this.state.token);
    }
    getProjectKey(membership) {
        if (!this.state)
            throw new Error('Not signed in');
        const cached = this.projectKeyCache.get(membership.project_id);
        if (cached)
            return cached;
        const jsonBytes = Buffer.from(membership.encrypted_project_key, 'base64');
        const encapsulated = JSON.parse(jsonBytes.toString('utf-8'));
        const key = (0, crypto_1.decapsulateProjectKey)(encapsulated, this.state.privateKey);
        this.projectKeyCache.set(membership.project_id, key);
        return key;
    }
    clearProjectKeys() {
        this.projectKeyCache.clear();
    }
    get baseUrl() {
        const cfg = vscode.workspace.getConfiguration('nivrit');
        return cfg.get('apiUrl') || 'http://localhost:4000';
    }
}
exports.SessionManager = SessionManager;
//# sourceMappingURL=session.js.map