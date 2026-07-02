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
exports.NivritTreeProvider = exports.NivritTreeItem = exports.TreeNodeKind = void 0;
const vscode = __importStar(require("vscode"));
const crypto_1 = require("./crypto");
var TreeNodeKind;
(function (TreeNodeKind) {
    TreeNodeKind["SignIn"] = "signin";
    TreeNodeKind["Org"] = "org";
    TreeNodeKind["Project"] = "project";
    TreeNodeKind["Environment"] = "environment";
    TreeNodeKind["Secret"] = "secret";
    TreeNodeKind["NoAccess"] = "noaccess";
})(TreeNodeKind || (exports.TreeNodeKind = TreeNodeKind = {}));
class NivritTreeItem extends vscode.TreeItem {
    id;
    kind;
    context;
    constructor(id, label, kind, collapsible, context = {}) {
        super(label, collapsible);
        this.id = id;
        this.kind = kind;
        this.context = context;
        this.contextValue = kind;
        switch (kind) {
            case TreeNodeKind.Org:
                this.iconPath = new vscode.ThemeIcon('organization');
                break;
            case TreeNodeKind.Project:
                this.iconPath = new vscode.ThemeIcon('repo');
                break;
            case TreeNodeKind.Environment:
                this.iconPath = new vscode.ThemeIcon('layers');
                break;
            case TreeNodeKind.Secret:
                this.iconPath = new vscode.ThemeIcon('key');
                this.command = {
                    command: 'nivrit.viewSecret',
                    title: 'View Secret',
                    arguments: [this],
                };
                break;
            case TreeNodeKind.SignIn:
                this.iconPath = new vscode.ThemeIcon('sign-in');
                this.command = { command: 'nivrit.signIn', title: 'Sign In' };
                break;
            case TreeNodeKind.NoAccess:
                this.iconPath = new vscode.ThemeIcon('error');
                break;
        }
    }
}
exports.NivritTreeItem = NivritTreeItem;
class NivritTreeProvider {
    session;
    output;
    _onDidChange = new vscode.EventEmitter();
    onDidChangeTreeData = this._onDidChange.event;
    membershipMap = new Map();
    constructor(session, output) {
        this.session = session;
        this.output = output;
    }
    refresh() {
        this.membershipMap.clear();
        this.session.clearProjectKeys();
        this._onDidChange.fire();
    }
    getTreeItem(element) {
        return element;
    }
    async getChildren(element) {
        if (!this.session.isSignedIn) {
            return [new NivritTreeItem('signin', 'Sign in to Nivrit', TreeNodeKind.SignIn, vscode.TreeItemCollapsibleState.None)];
        }
        try {
            if (!element) {
                return await this.loadOrgs();
            }
            switch (element.kind) {
                case TreeNodeKind.Org:
                    return await this.loadProjects(element.context.org);
                case TreeNodeKind.Project:
                    return await this.loadEnvironments(element.context.project, element.context.membership);
                case TreeNodeKind.Environment:
                    return await this.loadSecrets(element.context.project, element.context.environment, element.context.membership);
                default:
                    return [];
            }
        }
        catch (err) {
            this.output.appendLine(`Nivrit tree error: ${err?.message || err}`);
            vscode.window.showErrorMessage(`Nivrit: ${err?.message || err}`);
            return [];
        }
    }
    async loadOrgs() {
        const api = this.session.createApi();
        const orgs = await api.listOrgs();
        return orgs.map((org) => new NivritTreeItem(`org:${org.id}`, org.name, TreeNodeKind.Org, vscode.TreeItemCollapsibleState.Collapsed, { org }));
    }
    async loadProjects(org) {
        const api = this.session.createApi();
        const [projects, memberships] = await Promise.all([
            api.listOrgProjects(org.id),
            api.listMyProjects(),
        ]);
        for (const m of memberships) {
            this.membershipMap.set(m.project_id, m);
        }
        return projects.map((project) => {
            const membership = this.membershipMap.get(project.id);
            return new NivritTreeItem(`proj:${project.id}`, project.name, TreeNodeKind.Project, vscode.TreeItemCollapsibleState.Collapsed, { project, membership });
        });
    }
    async loadEnvironments(project, membership) {
        const api = this.session.createApi();
        const envs = await api.listEnvironments(project.id);
        return envs.map((env) => new NivritTreeItem(`env:${env.id}`, env.name, TreeNodeKind.Environment, vscode.TreeItemCollapsibleState.Collapsed, { project, membership, environment: env }));
    }
    async loadSecrets(project, environment, membership) {
        if (!membership) {
            return [
                new NivritTreeItem(`noaccess:${environment.id}`, 'No project access', TreeNodeKind.NoAccess, vscode.TreeItemCollapsibleState.None, { project, environment }),
            ];
        }
        const api = this.session.createApi();
        const secrets = await api.listSecrets(project.id, environment.id);
        return secrets.map((secret) => {
            const plaintext = this.decryptSecret(secret, membership);
            return new NivritTreeItem(`secret:${secret.id}`, secret.key, TreeNodeKind.Secret, vscode.TreeItemCollapsibleState.None, { project, membership, environment, secret, plaintext });
        });
    }
    decryptSecret(secret, membership) {
        if (!membership)
            return undefined;
        try {
            const projectKey = this.session.getProjectKey(membership);
            return (0, crypto_1.decryptValue)(secret.encrypted_value, secret.nonce, projectKey);
        }
        catch (err) {
            this.output.appendLine(`Failed to decrypt ${secret.key}: ${err?.message || err}`);
            return undefined;
        }
    }
}
exports.NivritTreeProvider = NivritTreeProvider;
//# sourceMappingURL=treeProvider.js.map