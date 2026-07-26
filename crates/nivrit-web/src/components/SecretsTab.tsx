import { useState } from 'react';
import {
  AlertTriangle,
  Copy,
  Eye,
  EyeOff,
  FileUp,
  FolderOpen,
  Pencil,
  Plus,
  Trash2,
  X,
} from './icons';
import {
  Badge,
  Button,
  Card,
  CardHeader,
  EmptyState,
  Input,
  Label,
} from './ui';
import type { SecretEntry } from '../session';

interface Org {
  id: string;
  name: string;
  slug: string;
}

interface Project {
  id: string;
  org_id: string;
  name: string;
  slug: string;
}

interface Environment {
  id: string;
  project_id: string;
  name: string;
  slug: string;
}

interface SecretsTabProps {
  orgs: Org[];
  selectedOrgId: string;
  setSelectedOrgId: (id: string) => void;
  projects: Project[];
  selectedProjectId: string;
  setSelectedProjectId: (id: string) => void;
  environments: Environment[];
  selectedEnvironmentId: string;
  setSelectedEnvironmentId: (id: string) => void;
  secrets: SecretEntry[];
  listing: boolean;
  secretKey: string;
  setSecretKey: (v: string) => void;
  secretValue: string;
  setSecretValue: (v: string) => void;
  editingSecretKey: string;
  onSetSecret: (e: React.FormEvent) => void;
  onDeleteSecret: (key: string) => void;
  onStartEdit: (secret: SecretEntry) => void;
  onCancelEdit: () => void;
  onOpenImport: () => void;
  newOrgName: string;
  setNewOrgName: (v: string) => void;
  newOrgSlug: string;
  setNewOrgSlug: (v: string) => void;
  onCreateOrg: (e: React.FormEvent) => void;
  newProjectName: string;
  setNewProjectName: (v: string) => void;
  newProjectSlug: string;
  setNewProjectSlug: (v: string) => void;
  onCreateProject: (e: React.FormEvent) => void;
  newEnvName: string;
  setNewEnvName: (v: string) => void;
  newEnvSlug: string;
  setNewEnvSlug: (v: string) => void;
  onCreateEnvironment: (e: React.FormEvent) => void;
  hasProjectKey: boolean;
}

export function SecretsTab(props: SecretsTabProps) {
  const selectedEnv = props.environments.find((e) => e.id === props.selectedEnvironmentId);
  const isEditing = props.editingSecretKey !== '';

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold tracking-tight text-slate-900 dark:text-white">
          Secrets
        </h1>
        <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">
          Manage encrypted environment variables for the selected project and environment.
        </p>
      </div>

      <div className="grid gap-4 lg:grid-cols-3">
        <CreateCard title="Create organization" description="Start a new team workspace.">
          <form onSubmit={props.onCreateOrg} className="space-y-3">
            <Input
              data-testid="org-name-input"
              placeholder="Organization name"
              value={props.newOrgName}
              onChange={(e) => props.setNewOrgName(e.target.value)}
              required
            />
            <Input
              data-testid="org-slug-input"
              placeholder="org-slug"
              value={props.newOrgSlug}
              onChange={(e) => props.setNewOrgSlug(e.target.value)}
              required
            />
            <Button type="submit" data-testid="create-org-btn" className="w-full">
              Create organization
            </Button>
          </form>
        </CreateCard>

        {props.selectedOrgId && (
          <CreateCard title="Create project" description="A project holds environments and secrets.">
            <form onSubmit={props.onCreateProject} className="space-y-3">
              <Input
                data-testid="project-name-input"
                placeholder="Project name"
                value={props.newProjectName}
                onChange={(e) => props.setNewProjectName(e.target.value)}
                required
              />
              <Input
                data-testid="project-slug-input"
                placeholder="project-slug"
                value={props.newProjectSlug}
                onChange={(e) => props.setNewProjectSlug(e.target.value)}
                required
              />
              <Button type="submit" data-testid="create-project-btn" className="w-full">
                Create project
              </Button>
            </form>
          </CreateCard>
        )}

        {props.selectedProjectId && (
          <CreateCard title="Create environment" description="For example: production, staging, dev.">
            <form onSubmit={props.onCreateEnvironment} className="space-y-3">
              <Input
                data-testid="env-name-input"
                placeholder="Environment name"
                value={props.newEnvName}
                onChange={(e) => props.setNewEnvName(e.target.value)}
                required
              />
              <Input
                data-testid="env-slug-input"
                placeholder="env-slug"
                value={props.newEnvSlug}
                onChange={(e) => props.setNewEnvSlug(e.target.value)}
                required
              />
              <Button type="submit" data-testid="create-env-btn" className="w-full">
                Create environment
              </Button>
            </form>
          </CreateCard>
        )}
      </div>

      {props.selectedProjectId && !props.hasProjectKey && (
        <div className="flex items-start gap-3 rounded-xl border border-amber-200 bg-amber-50 p-4 dark:border-amber-900/50 dark:bg-amber-900/20">
          <AlertTriangle className="mt-0.5 text-amber-600 dark:text-amber-400" size={20} />
          <div>
            <p className="text-sm font-medium text-amber-800 dark:text-amber-200">
              Project key not available
            </p>
            <p className="text-sm text-amber-700 dark:text-amber-300/80">
              You may need to be invited to this project before you can view or edit secrets.
            </p>
          </div>
        </div>
      )}

      {props.selectedProjectId && props.selectedEnvironmentId && props.hasProjectKey && (
        <Card>
          <CardHeader
            title={
              <span className="flex items-center gap-2">
                Environment secrets
                {selectedEnv && <Badge>{selectedEnv.name}</Badge>}
              </span>
            }
            description="Add, reveal, copy, edit, or remove secrets. Values are decrypted locally in your browser."
          />

          <div className="border-t border-slate-100 p-5 dark:border-slate-800">
            <form onSubmit={props.onSetSecret} className="mb-6 flex flex-wrap items-start gap-3">
              <div className="min-w-[180px] flex-1">
                <Label htmlFor="secret-key" className="sr-only">
                  Secret key
                </Label>
                <Input
                  id="secret-key"
                  data-testid="secret-key-input"
                  placeholder="Secret key"
                  value={props.secretKey}
                  onChange={(e) => props.setSecretKey(e.target.value)}
                  disabled={isEditing}
                  required
                />
                {isEditing && (
                  <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">
                    Key is locked while editing. Cancel to change it.
                  </p>
                )}
              </div>
              <div className="min-w-[180px] flex-1">
                <Label htmlFor="secret-value" className="sr-only">
                  Secret value
                </Label>
                <Input
                  id="secret-value"
                  data-testid="secret-value-input"
                  placeholder="Secret value"
                  value={props.secretValue}
                  onChange={(e) => props.setSecretValue(e.target.value)}
                  required
                />
              </div>
              <div className="flex items-center gap-2">
                <Button type="submit" data-testid="set-secret-btn">
                  {isEditing ? (
                    <>
                      <Pencil size={16} />
                      Update secret
                    </>
                  ) : (
                    <>
                      <Plus size={16} />
                      Add secret
                    </>
                  )}
                </Button>
                {isEditing && (
                  <Button
                    type="button"
                    variant="ghost"
                    size="icon"
                    onClick={props.onCancelEdit}
                    title="Cancel edit"
                    aria-label="Cancel edit"
                  >
                    <X size={16} />
                  </Button>
                )}
                {!isEditing && (
                  <Button
                    type="button"
                    variant="secondary"
                    onClick={props.onOpenImport}
                    title="Import from .env"
                    aria-label="Import from .env"
                  >
                    <FileUp size={16} />
                    <span className="hidden sm:inline">Import .env</span>
                  </Button>
                )}
              </div>
            </form>

            {props.listing ? (
              <div className="flex items-center gap-2 text-sm text-slate-500">
                <div className="h-4 w-4 animate-spin rounded-full border-2 border-slate-300 border-t-primary-600" />
                Loading secrets…
              </div>
            ) : props.secrets.length === 0 ? (
              <EmptyState
                icon={FolderOpen}
                title="No secrets yet"
                description="Add your first secret above or import an existing .env file."
                action={
                  <Button variant="secondary" onClick={props.onOpenImport}>
                    <FileUp size={16} />
                    Import from .env
                  </Button>
                }
              />
            ) : (
              <div className="overflow-x-auto rounded-lg border border-slate-200 dark:border-slate-800">
                <table className="w-full text-left text-sm">
                  <thead className="bg-slate-50 dark:bg-slate-900/50">
                    <tr>
                      <th className="px-4 py-3 font-semibold text-slate-500 dark:text-slate-400">
                        Key
                      </th>
                      <th className="px-4 py-3 font-semibold text-slate-500 dark:text-slate-400">
                        Value
                      </th>
                      <th className="px-4 py-3 font-semibold text-slate-500 dark:text-slate-400">
                        Version
                      </th>
                      <th className="px-4 py-3 text-right"></th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
                    {props.secrets.map((s) => (
                      <SecretRow
                        key={s.id}
                        secret={s}
                        onDelete={props.onDeleteSecret}
                        onEdit={props.onStartEdit}
                      />
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </Card>
      )}
    </div>
  );
}

function CreateCard({
  title,
  description,
  children,
}: {
  title: string;
  description: string;
  children: React.ReactNode;
}) {
  return (
    <Card className="p-5">
      <h3 className="text-sm font-semibold text-slate-900 dark:text-white">{title}</h3>
      <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">{description}</p>
      <div className="mt-4">{children}</div>
    </Card>
  );
}

function SecretRow({
  secret,
  onDelete,
  onEdit,
}: {
  secret: SecretEntry;
  onDelete: (k: string) => void;
  onEdit: (s: SecretEntry) => void;
}) {
  const [revealed, setRevealed] = useState(false);

  return (
    <tr className="bg-white hover:bg-slate-50 dark:bg-slate-900 dark:hover:bg-slate-800/50">
      <td className="px-4 py-3 font-medium text-slate-900 dark:text-slate-100">{secret.key}</td>
      <td className="px-4 py-3 font-mono text-slate-600 dark:text-slate-300">
        {revealed ? secret.value : '•'.repeat(Math.min(secret.value.length, 12))}
      </td>
      <td className="px-4 py-3 text-slate-500">
        <Badge variant="default">v{secret.version}</Badge>
      </td>
      <td className="px-4 py-3">
        <div className="flex items-center justify-end gap-1">
          <Button
            type="button"
            variant="ghost"
            size="icon"
            onClick={() => onEdit(secret)}
            title="Edit"
            aria-label="Edit"
          >
            <Pencil size={16} />
          </Button>
          <Button
            type="button"
            variant="ghost"
            size="icon"
            onClick={() => setRevealed(!revealed)}
            title={revealed ? 'Hide' : 'Show'}
            aria-label={revealed ? 'Hide' : 'Show'}
          >
            {revealed ? <EyeOff size={16} /> : <Eye size={16} />}
          </Button>
          <Button
            type="button"
            variant="ghost"
            size="icon"
            onClick={() => navigator.clipboard.writeText(secret.value)}
            title="Copy"
            aria-label="Copy"
          >
            <Copy size={16} />
          </Button>
          <Button
            type="button"
            variant="ghost"
            size="icon"
            onClick={() => onDelete(secret.key)}
            title="Delete"
            aria-label="Delete"
            className="text-red-600 hover:bg-red-50 dark:text-red-400 dark:hover:bg-red-900/20"
          >
            <Trash2 size={16} />
          </Button>
        </div>
      </td>
    </tr>
  );
}
