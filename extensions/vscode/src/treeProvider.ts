import * as vscode from 'vscode';
import {
  NivritApi,
  NivritEnvironment,
  NivritOrg,
  NivritProject,
  NivritProjectMembership,
  NivritSecret,
} from './api';
import { SessionManager } from './session';
import { decryptValue } from './crypto';

export enum TreeNodeKind {
  SignIn = 'signin',
  Org = 'org',
  Project = 'project',
  Environment = 'environment',
  Secret = 'secret',
  NoAccess = 'noaccess',
}

export class NivritTreeItem extends vscode.TreeItem {
  constructor(
    public readonly id: string,
    label: string,
    public readonly kind: TreeNodeKind,
    collapsible: vscode.TreeItemCollapsibleState,
    public readonly context: {
      org?: NivritOrg;
      project?: NivritProject;
      membership?: NivritProjectMembership;
      environment?: NivritEnvironment;
      secret?: NivritSecret;
      plaintext?: string;
    } = {}
  ) {
    super(label, collapsible);
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

export class NivritTreeProvider implements vscode.TreeDataProvider<NivritTreeItem> {
  private _onDidChange = new vscode.EventEmitter<NivritTreeItem | undefined | void>();
  public readonly onDidChangeTreeData = this._onDidChange.event;

  private membershipMap = new Map<string, NivritProjectMembership>();

  constructor(
    private readonly session: SessionManager,
    private readonly output: vscode.OutputChannel
  ) {}

  refresh(): void {
    this.membershipMap.clear();
    this.session.clearProjectKeys();
    this._onDidChange.fire();
  }

  getTreeItem(element: NivritTreeItem): vscode.TreeItem {
    return element;
  }

  async getChildren(element?: NivritTreeItem): Promise<NivritTreeItem[]> {
    if (!this.session.isSignedIn) {
      return [new NivritTreeItem('signin', 'Sign in to Nivrit', TreeNodeKind.SignIn, vscode.TreeItemCollapsibleState.None)];
    }

    try {
      if (!element) {
        return await this.loadOrgs();
      }

      switch (element.kind) {
        case TreeNodeKind.Org:
          return await this.loadProjects(element.context.org!);
        case TreeNodeKind.Project:
          return await this.loadEnvironments(element.context.project!, element.context.membership);
        case TreeNodeKind.Environment:
          return await this.loadSecrets(element.context.project!, element.context.environment!, element.context.membership);
        default:
          return [];
      }
    } catch (err: any) {
      this.output.appendLine(`Nivrit tree error: ${err?.message || err}`);
      vscode.window.showErrorMessage(`Nivrit: ${err?.message || err}`);
      return [];
    }
  }

  private async loadOrgs(): Promise<NivritTreeItem[]> {
    const api = this.session.createApi();
    const orgs = await api.listOrgs();
    return orgs.map(
      (org) =>
        new NivritTreeItem(
          `org:${org.id}`,
          org.name,
          TreeNodeKind.Org,
          vscode.TreeItemCollapsibleState.Collapsed,
          { org }
        )
    );
  }

  private async loadProjects(org: NivritOrg): Promise<NivritTreeItem[]> {
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
      return new NivritTreeItem(
        `proj:${project.id}`,
        project.name,
        TreeNodeKind.Project,
        vscode.TreeItemCollapsibleState.Collapsed,
        { project, membership }
      );
    });
  }

  private async loadEnvironments(
    project: NivritProject,
    membership?: NivritProjectMembership
  ): Promise<NivritTreeItem[]> {
    const api = this.session.createApi();
    const envs = await api.listEnvironments(project.id);
    return envs.map(
      (env) =>
        new NivritTreeItem(
          `env:${env.id}`,
          env.name,
          TreeNodeKind.Environment,
          vscode.TreeItemCollapsibleState.Collapsed,
          { project, membership, environment: env }
        )
    );
  }

  private async loadSecrets(
    project: NivritProject,
    environment: NivritEnvironment,
    membership?: NivritProjectMembership
  ): Promise<NivritTreeItem[]> {
    if (!membership) {
      return [
        new NivritTreeItem(
          `noaccess:${environment.id}`,
          'No project access',
          TreeNodeKind.NoAccess,
          vscode.TreeItemCollapsibleState.None,
          { project, environment }
        ),
      ];
    }

    const api = this.session.createApi();
    const secrets = await api.listSecrets(project.id, environment.id);
    return secrets.map((secret) => {
      const plaintext = this.decryptSecret(secret, membership);
      return new NivritTreeItem(
        `secret:${secret.id}`,
        secret.key,
        TreeNodeKind.Secret,
        vscode.TreeItemCollapsibleState.None,
        { project, membership, environment, secret, plaintext }
      );
    });
  }

  decryptSecret(secret: NivritSecret, membership?: NivritProjectMembership): string | undefined {
    if (!membership) return undefined;
    try {
      const projectKey = this.session.getProjectKey(membership);
      return decryptValue(secret.encrypted_value, secret.nonce, projectKey);
    } catch (err: any) {
      this.output.appendLine(`Failed to decrypt ${secret.key}: ${err?.message || err}`);
      return undefined;
    }
  }
}
